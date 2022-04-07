#ifndef UNTITLED_WINPEMGR_HPP
#define UNTITLED_WINPEMGR_HPP

#include <windows.h>
#include <WinNT.h>

#include <cstdint>
#include <string>
#include <vector>

#include <WinTrust.h>

#ifndef CERT_SECTION_TYPE_ANY
#define CERT_SECTION_TYPE_ANY 255
#endif

namespace nsCmn
{
    namespace nsPE
    {
        namespace nsDetail
        {
            struct TyRsrcData;
            struct TyRsrcDirectoryEntry;
            struct TyRsrcDirectory;

            // WrittenAt 변수의 용도
            // 리소스를 파일에 기록할 때, 각 구조체에는 OffsetToData, OffsetToDirectory 를 기록해야하는데
            // 해당 값은 리소스 섹션의 시작위치로부터의 상대위치이다.
            // 데이터를 버퍼에 기록한 후, 해당 버퍼의 주소값을 WrittenAt 값에 넣은 후,
            // 최초 리소스 섹션 시작위치로부터 빼기 연산을 통해 Offset 을 구한다

            // 리소스의 말단 노드
            struct TyRsrcData
            {
                TyRsrcData() = default;
                TyRsrcData( uint8_t* Buffer, uint32_t BufferSize, DWORD CodePage = 0, DWORD Offset = 0 );

                DWORD                                   GetSize() { return Buffer.size(); }
                void                                    SetData( uint8_t* Buffer, uint32_t BufferSize );

                std::vector< uint8_t >  Buffer;
                DWORD                   CodePage = 0;
                DWORD                   Offset = 0;

                ULONG_PTR               WrittenAt = 0;
            };

            struct TyRsrcDirectoryEntry
            {
                TyRsrcDirectoryEntry( const WCHAR* Name, TyRsrcDirectory* Child );
                TyRsrcDirectoryEntry( const WCHAR* Name, TyRsrcData* Data );

                ~TyRsrcDirectoryEntry()
                {
                    if( Directory )
                        delete Directory;
                    if( Leaf )
                        delete Leaf;
                }

                WORD                                    GetId() const { return Id; }
                TyRsrcDirectory*                        GetChild();
                TyRsrcData*                             GetData();

                // NameOrId
                bool                    IsName = false;
                std::wstring            Name;
                WORD                    Id = 0;

                // DataOrDirectory
                bool                    IsDirectory = false;
                TyRsrcDirectory*        Directory = nullptr;
                TyRsrcData*             Leaf = nullptr;

                ULONG_PTR               WrittenAt = 0;
            };

            struct TyRsrcDirectory
            {
                TyRsrcDirectory( IMAGE_RESOURCE_DIRECTORY* Res );
                virtual ~TyRsrcDirectory() { Destroy(); }

                IMAGE_RESOURCE_DIRECTORY                GetInfo() const;
                // Get the size of this resource directory (including all of its children)
                DWORD                                   GetSize();
                // Destroys this directory and all of its children
                void                                    Destroy();

                TyRsrcDirectoryEntry*                   GetEntry( uint32_t Index );
                // This function inserts a new directory entry
                // It also keeps the directory entries sorted
                void                                    AddEntry( TyRsrcDirectoryEntry* Entry );
                void                                    RemoveEntry( uint32_t Idx );
                int                                     CountEntries() const;

                // Returns the index of a directory entry with the specified name
                // Name can be a string or an id
                // Returns UINT_MAX if can not be found
                 uint32_t                               FindIndex( wchar_t* Name );

                // Returns the index of a directory entry with the specified id
                // Returns UINT_MAX if can not be found
                uint32_t                                FindIndex( WORD Id );

                IMAGE_RESOURCE_DIRECTORY                Rsrc = {0,};
                std::vector< TyRsrcDirectoryEntry* >    Entries;

                ULONG_PTR                               WrittenAt = 0;
            };
        }

        DWORD CvtRVAToOFFSET( IMAGE_SECTION_HEADER* pISH, DWORD RVA );
        DWORD CvtOFFSETToRVA( IMAGE_SECTION_HEADER* pISH, DWORD OFFSET );

        template< typename T >
        T ROUND_UP( T Value, uint32_t PowerOf2 )
        {
            return ( ( ( Value ) + ( PowerOf2 - 1 ) ) & ~( PowerOf2 - 1 ) );
        }

#define GET_NT_HDR_OFFSET(pb) (PIMAGE_DOS_HEADER(pb)->e_lfanew)
#define GET_NT_HDR_PTR(pb) ((PIMAGE_NT_HEADERS)((PBYTE)(pb) + GET_NT_HDR_OFFSET(pb)))

#ifndef GetMemberFromOptionalHeader
#define GetMemberFromOptionalHeader(optionalHeader, member) \
    ( (optionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC) ? \
      ((PIMAGE_OPTIONAL_HEADER32)&optionalHeader)->member : \
      ((PIMAGE_OPTIONAL_HEADER64)&optionalHeader)->member \
    )
#endif

        inline bool IsDosSignature( const PBYTE Base ) { return (( IMAGE_DOS_HEADER* )Base)->e_magic == IMAGE_DOS_SIGNATURE; }
        inline bool IsNTSignature( PBYTE Base ) { return ( ( IMAGE_NT_HEADERS32* )GET_NT_HDR_PTR( Base ) )->Signature == IMAGE_NT_SIGNATURE; }
        inline bool Is32bitPE( PBYTE Base ) { return *( ( WORD* )( ((PBYTE)GET_NT_HDR_PTR( Base )) + sizeof( DWORD ) + sizeof( IMAGE_FILE_HEADER ) ) ) == IMAGE_NT_OPTIONAL_HDR32_MAGIC; }

        template< typename T = PVOID >
        T AddToPtr( PVOID Ptr, uint32_t Offset )
        {
            return ( T )(PVOID)( ( (PUCHAR) Ptr ) + Offset );
        }

        /*!
         * PE 파일의 정보 읽기 / 수정 등이 가능한 관리 클래스
         *
         * 동작 모드
         *      읽기 전용, MMF 를 통해 작동되며 PE 파일을 수정할 수 없다
         *      편집 가능, PE 파일을 읽어 메모리에 복사본을 만들어서 작업을 수행한다
         */
        class CPEMgr
        {
        public:
            enum TyEnFileType
            {
                PE_FILE_TYPE_UNKNOWN,
                PE_FILE_TYPE_DOS,
                PE_FILE_TYPE_NT_X86,
                PE_FILE_TYPE_NT_X64,
                PE_FILE_TYPE_NT_DOTNET
            };

        public:
            ~CPEMgr();

            DWORD           SetFile( const std::wstring& FilePath, bool IsReadOnly );
            TyEnFileType    GetFileType() const;
            PBYTE           GetBase() const { return (PBYTE)_base; }

            std::pair< IMAGE_NT_HEADERS*, std::wstring > GetNTHeaders( PBYTE Base = nullptr );
            std::pair< uint8_t*, uint32_t > GetPE();

            /*!
             * @brief 수정사항을 반영한 새로운 PE 파일을 생성하여 반환합니다
             * @return PE 파일을 담고있는 버퍼
             */
            std::vector< uint8_t >      RebuildPE();
            DWORD                       CalcChecksum();

            ///////////////////////////////////////////////////////////////////
            /// 리소스 관리

            // 리소스 섹션의 크기를 산출합니다.
            // NOTE: 해당 크기는 정렬을 적용하지 않은 크기입니다.
            DWORD                       CalcSizeOfRsrc();
            std::vector<uint8_t>        GetResource( WCHAR* Type, WCHAR* NameOrId, LANGID LangID = 0 );
            bool                        UpdResource( WCHAR* Type, WCHAR* NameOrId, std::vector< uint8_t >& Buffer, LANGID LangID = 0 );
            bool                        UpdResource( WCHAR* Type, WCHAR* NameOrId, uint8_t* Buffer, uint32_t BufferSize, LANGID LangID = 0 );

            /*!
             * @param TypeFilter The certificate section type to be used as a filter when returning certificate information. CERT_SECTION_TYPE_ANY should be passed for information on all section types present in the image
             * @param CertificateCount A pointer to a variable that receives the number of certificates in the image containing sections of the type specified by the TypeFilter parameter. If none are found, this parameter is zero.
             * @param Indices Optionally provides a buffer to use to return an array of indices to the certificates containing sections of the specified type. No ordering should be assumed for the index values, nor are they guaranteed to be contiguous when CERT_SECTION_TYPE_ANY is queried.
               @param IndexCount The size of the Indices buffer, in DWORDs. This parameter will be examined whenever Indices is present. If CertificateCount is greater than IndexCount, Indices will be filled in with the first IndexCount sections found in the image; any others will not be returned.
            */
            bool                        EnumerateCertificates( _In_ WORD TypeFilter, _Out_ PDWORD CertificateCount, _Inout_ PDWORD Indices, _In_opt_ DWORD IndexCount );
            bool                        GetCertificateHeader( _In_ DWORD CertificateIndex, _Inout_ LPWIN_CERTIFICATE CertificateHeader );
            /*!
             * @brief 불러온 파일에서 디지털 서명이 있다면 제거합니다.
             * @return 제거 성공 여부를 반환합니다. 존재하지 않았다면 true 반환, readonly 모드라면 false 반환, 존재하지만 실패했다면 false 반환
             */
            bool                        RemoveCertificates();
            DWORD                       GetCertificateCount();

        private:

            void                        cleanup();

            DWORD                       scan();
            nsDetail::TyRsrcDirectory*  scanRsrcSection( IMAGE_RESOURCE_DIRECTORY* Root, IMAGE_RESOURCE_DIRECTORY* Target );

            IMAGE_SECTION_HEADER*       firstSecHDR( uint8_t* Base, DWORD* SectionCount = nullptr ) const;
            /*!
             * @brief PE 이미지에서 지정한 RVA 가 속한 섹션 헤더를 찾는다
            */
            IMAGE_SECTION_HEADER*       findSecHDRByRVA( uint8_t* ImgBase, DWORD RVA, DWORD* SecIndex = NULL ) const;
            IMAGE_SECTION_HEADER*       findSecHDRByOffset( uint8_t* ImgBase, DWORD Offset );

            IMAGE_DATA_DIRECTORY*       retrieveDataDirs( uint8_t* ImageBase );
            IMAGE_DATA_DIRECTORY*       retrieveDataDirById( uint8_t* ImageBase, ULONG Id );

            DWORD                       calcChecksum( uint8_t* ImgBase, uint32_t ImgSize );
            DWORD                       calcSizeOfImage( uint8_t* ImageBase );
            DWORD                       calcSizeOfHeaders(  uint8_t* ImageBase );
            DWORD                       calcInitializedDataSize( uint8_t* base );

            ///////////////////////////////////////////////////////////////////
            /// 리소스 관리

            DWORD                       calcSizeOfRsrc( nsDetail::TyRsrcDirectory* Dir );
            void                        writeRsrcSecTo( BYTE* Dst );
            DWORD                       patchRVAs( PBYTE Src, uint32_t SrcSize, std::vector< uint8_t>& Dst,
                                                   IMAGE_NT_HEADERS* SrcNtHDR, IMAGE_NT_HEADERS* DstNtHR,
                                                   DWORD Delta, DWORD RVADelta );
            void                        writeRsrcSecPaddingTo( BYTE* res_base, DWORD Size );

            // 버퍼에 리소스를 기록한 후, 구조체에 적절한 OffsetToData, OffsetToDirectory 값을 채운다
            void                        setRsrcOffsets( nsDetail::TyRsrcDirectory* RsrcDir, ULONG_PTR From );

            IMAGE_SECTION_HEADER*       retrieveRsrcSection( const PBYTE ImgBase ) const;
            // Returns a copy of the requested resource
            // Returns 0 if the requested resource can't be found
            std::vector<uint8_t>        getResource( WCHAR* Type, WCHAR* Name, LANGID Language );
            // Adds/Replaces/Removes a resource.
            // If Buffer is empty UpdateResource removes the resource.
            bool                        updResource( WCHAR* Type, WCHAR* Name, LANGID Language, uint8_t* Buffer, uint32_t BufferSize );

            ///////////////////////////////////////////////////////////////////
            /// 디지털 서명 관리

            bool                        retrieveSecurityDirOffset( PBYTE ImgBase, DWORD* pdwOfs, DWORD* pdwSize );
            // Idx = 0 부터 시작한다
            // 지정한 인증서의 위치 및 크기를 반환,
            bool                        retrieveCertificateOffset( PBYTE ImgBase, uint32_t ImgSize, DWORD Idx, DWORD* pdwOfs, DWORD* pdwSize );
            bool                        removeCertificate( PBYTE& ImgBase, int64_t& ImgSize, _In_ DWORD Index );
            bool                        getCertificate( PBYTE ImgBase, uint32_t ImgSize, DWORD Index, LPWIN_CERTIFICATE* Certificate );

            ///////////////////////////////////////////////////////////////////
            ///

            bool                        _isReadOnly = false;
            HANDLE                      _hFile = INVALID_HANDLE_VALUE;
            uint8_t*                    _base = nullptr;
            int64_t                     _baseSize = 0;
            TyEnFileType                _eFileType = PE_FILE_TYPE_UNKNOWN;

            nsDetail::TyRsrcDirectory*  _resRoot = nullptr;
        };
    }
}

#endif //UNTITLED_WINPEMGR_HPP
